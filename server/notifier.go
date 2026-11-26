package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Rehaan15790/belphegor/db"
	"github.com/Rehaan15790/belphegor/notify"
)

// Global setting keys (stored in the settings key-value table, no table creation needed).
const (
	// settingNotifyEnabled is the master push switch. On by default: it is for stopping the bleeding in one click during maintenance,
	// not a condition for enabling the feature; the real condition is whether a channel is configured.
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL is the external access address used to build the vulnerability detail backlink
	// (e.g. https://belphegor.example.com). If empty, messages carry no backlink button.
	// The project has no reusable external address configuration, so one is added here.
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes is the digest mode period (minutes).
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick is the polling interval of the delivery engine. 3 seconds is the upper bound of this engine's real-time behavior,
	// and is also the main source of delay between a vulnerability being stored and the message reaching IM.
	notifyTick = 3 * time.Second
	// When notifyBackgroundDisabledEnv is set, the server does not start the background delivery loop
	// (newNotifier(s).Run). Integration tests call stepRealtime and stepDigest
	// directly to verify distribution results deterministically, but if the 3-second background loop
	// handles the same channel at the same time, the tally wobbles with timing. This is a test-only switch
	// to prevent that; if the variable is absent, startup is as usual (production behavior unchanged).
	notifyBackgroundDisabledEnv = "BELPHEGOR_NOTIFY_BACKGROUND_DISABLED"
	// notifyLease is the lease duration when claiming a delivery. It must be significantly longer than the worst-case time of a single delivery
	// (the notify package's HTTP client timeout of 15 seconds), otherwise the same row could be delivered by two
	// dispatchers at once.
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick limits the number of events dispatched per round, to avoid expanding the whole historical backlog
	// into delivery tasks at once when a channel is first enabled.
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes is the default digest period.
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick is the per-round delivery cap for a channel with no rate limit set.
	// It exists to prevent "a channel configured as unlimited + one scan producing thousands of vulnerabilities" from
	// dragging a single loop round into a long block.
	notifyUnlimitedBurstPerTick = 50
	// notifyMaxSendsPerChannelPerTick is the maximum number of deliveries per channel per round.
	//
	// This cap is derived backwards from the **lease duration**: claiming puts a lease on the row (notifyLease = 3 minutes),
	// and if a round delivers so many items serially that the worst-case time exceeds the lease, the lease of the last few expires before they are sent.
	// Within a single process it does not matter (Run is a single goroutine running serially, so a tick never re-enters), but when **two
	// processes connect to the same database**, the other side re-claims the rows whose lease expired and sends them again, also
	// double-incrementing attempts and judging them failed while the original process is still delivering.
	//
	// Value: 3-minute lease / 30-second single timeout = 6 uses the lease **exactly**, with zero margin,
	// so it cannot be chosen; 5 makes the worst case 150 seconds and leaves a 30-second margin. This relationship is pinned by
	// TestNotifyTickBudgetFitsWithinLease: changing any one of notifyLease,
	// notifySendTimeout or this value makes that assertion fail.
	notifyMaxSendsPerChannelPerTick = 5
	// notifySendTimeout is the timeout of a single delivery. It also determines the value of the previous constant;
	// the two multiplied must not exceed notifyLease, see TestNotifyTickBudgetFitsWithinLease.
	notifySendTimeout = 30 * time.Second
)

// notifyBackoff is the backoff sequence for failed retries, indexed by the number of attempts made.
// The 3 chances (including the first) correspond to db.MaxNotifyAttempts; the two must be changed together.
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

const (
	errDeliveryChannelKindUnregistered = "Unregistered channel type: %q"
	errDeliverySnapshotUnrenderable    = "Could not parse the event snapshot, so this vulnerability could not be turned into a message"
	errDeliveryChannelLengthCapped     = "This message reached the channel length limit, so only the first %d were sent and the rest are deferred to the next batch"
	errDeliveryNoDeliveredCount        = "The channel did not report the number of messages sent (delivered=%d)"
	errDeliveryRetryExhausted          = "Still failed after %d retries: %s"
	errDeliverySnapshotEmpty           = "The event snapshot for delivery item #%d is empty"
	errDeliverySnapshotParse           = "Failed to parse the event snapshot of delivery item #%d: %w"
	errDeliveryBatchAllUnparseable     = "Failed to parse all %d deliveries in the summary batch"
)

// Notifier is the delivery engine for vulnerability push notifications.
//
// It runs as its own goroutine alongside Scheduler (see server.New). It deliberately does not reuse
// the Scheduler tick: push needs real-time latency (3 seconds), which differs from the trigger's business cadence,
// and the two fail independently: a stuck push must not affect agent triggers.
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu protects buckets. There are few channels and little contention, so one mutex is enough;
	// a finer-grained structure is not worth it.
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket is the token bucket of a single channel.
//
// A token bucket is used instead of a sliding window that counts per minute and resets, because the latter has bad boundary effects:
// sending 20 at the end of a window and another 20 right after is 40 within a second for the platform,
// which gets rate limited; a token bucket refills at a constant rate and avoids such bursts naturally.
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run loops until ctx ends. Started once by server.New.
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step runs one round: first dispatch new events, then deliver the tasks that are due.
//
// A failure in any step is only logged and never breaks the loop: a notification system fault must never escalate into a process-level problem.
// Each tick is independent, and the next round retries naturally.
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] failed to dispatch events: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] failed to read channels: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// The token bucket is measured in **messages** (equivalent to HTTP requests), not vulnerabilities.
		// In realtime mode the two are the same (one vulnerability, one message); in digest mode a whole batch of vulnerabilities is merged into
		// one message, so it consumes only one token.
		//
		// In both modes, ask the token bucket first and then claim by quota; the order must not be reversed, or a
		// delivery blocked by rate limiting would already have used up a retry attempt.
		now := time.Now()
		if ch.Mode == db.NotifyModeDigest {
			tokens, claimLimit := digestTickPlan()
			if n.takeTokens(ch.ID, ch.RatePerMin, tokens, now) <= 0 {
				continue
			}
			n.stepDigest(ctx, ch, claimLimit, baseURL)
			continue
		}
		allow := n.takeTokens(ch.ID, ch.RatePerMin, notifyMaxSendsPerChannelPerTick, now)
		if allow <= 0 {
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// digestTickPlan returns, for a digest channel in this round, the token cost and the upper bound of the batch size.
//
// The two return values are **two different units**, which is why this is its own function:
//
//   - tokens is a message count. A batch of vulnerabilities is merged into one message and sent with one HTTP request, so it is always 1.
//     rate_per_min therefore still applies to digest (at most this many digest messages per minute).
//   - claimLimit is the maximum number of vulnerabilities in one batch. It is bounded only by memory and has nothing to do with the request budget.
//
// Once, to make rate_per_min apply to digest, the per-round request budget
// (notifyMaxSendsPerChannelPerTick, derived from the lease) was passed down directly as the batch size.
// The result: a channel with rate_per_min=20 only refills 1 token in a 3-second tick, so every digest
// message held only 1 vulnerability. Digest degraded into "realtime push with digest wording", readers got a stream of
// "1 new vulnerability in the last 30 minutes", and db.MaxDigestBatchSize could never be reached.
//
// This symptom is hard to spot in end-to-end tests (existing cases all pass a large enough limit by hand to
// stepDigest, bypassing the quota calculation in step), so the decision is kept here and pinned directly by
// TestDigestTickPlanDecouplesBatchSizeFromSendBudget.
func digestTickPlan() (tokens, claimLimit int) {
	return 1, db.MaxDigestBatchSize
}

// stepRealtime claims and delivers the realtime tasks of a channel, one message per vulnerability.
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] failed to claim realtime deliveries channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf(errDeliveryChannelKindUnregistered, ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// A render failure is a local data problem; retrying will not help.
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest aggregates the pending deliveries of a channel into one message and sends it when the batch is due.
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] failed to evaluate digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] failed to claim digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf(errDeliveryChannelKindUnregistered, ch.Kind))
		return
	}
	msg, included, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	// Deliveries whose snapshot is broken and that did not make it into the message must be failed explicitly. Otherwise they stay
	// outside included, in neither the message nor the failure list. When the send succeeds, their status is missed by
	// the later bulk marking and stays at sending until the lease expires and they are claimed again and again.
	if skipped := excludeDeliveries(deliveries, included); len(skipped) > 0 {
		reason := errDeliverySnapshotUnrenderable
		if fErr := n.pg.FailDeliveries(ctx, deliveryIDs(skipped), reason); fErr != nil {
			log.Printf("[notify] failed to mark deliveries with bad snapshots channel=%s ids=%v: %v", ch.Kind, deliveryIDs(skipped), fErr)
		}
		log.Printf("[notify] skipped %d deliveries with unparsable snapshots channel=%d", len(skipped), ch.ID)
	}
	// Hand only the deliveries that made it into the message to send: included[i] corresponds strictly to msg.Items[i],
	// and send relies on this correspondence to apply "the channel reported that the first K fit" to the correct delivery rows.
	n.send(ctx, channel, cfg, msg, included)
}

// send delivers and moves the status along according to the result.
//
// The deliveries of one batch (possibly dozens in digest mode) share one send result: either all delivered, or the whole batch is retried.
// There is no per-item retry: a digest message is a single message, and resending part of it would corrupt the batch semantics.
//
// The only exception is **segmentation caused by the channel length limit**: if the channel reports that only the first K fit,
// then item K+1 onward must wait for the next batch instead of being marked successful along with the rest. Otherwise the truncated
// vulnerabilities are in neither the message nor the failure list, and vanish completely.
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	// Put a limit on a single delivery so one stuck channel cannot hold up all the remaining channels in this round.
	sendCtx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	delivered, err := channel.Send(sendCtx, cfg, msg)
	if err == nil && delivered > 0 {
		if delivered > len(deliveries) {
			// The count reported by the channel cannot exceed the number of deliveries; if it does, the rendering layer miscounted.
			// Treat all as delivered and log the problem; that is better than corrupting the records.
			log.Printf("[notify] channel reported %d delivered, more than the %d sent channel=%s; treating all as delivered",
				delivered, len(deliveries), channel.Kind())
			delivered = len(deliveries)
		}
		sent, rest := deliveries[:delivered], deliveries[delivered:]
		if err := n.pg.MarkDeliveriesSent(ctx, deliveryIDs(sent)); err != nil {
			log.Printf("[notify] failed to mark as delivered channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(sent), err)
		}
		if len(rest) > 0 {
			// This message has reached the channel length limit: put the rest straight back in the queue for the next tick to continue.
			// Use DeferDeliveries rather than RescheduleDeliveries: this is not a failure
			// and must not use up the retry budget (the claim already added +1 optimistically, and it is subtracted back there).
			if err := n.pg.DeferDeliveries(ctx, deliveryIDs(rest),
				fmt.Sprintf(errDeliveryChannelLengthCapped, delivered)); err != nil {
				log.Printf("[notify] failed to queue remaining segments channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(rest), err)
			}
		}
		return
	}
	if err == nil {
		// The channel returned no error and did not say how many were delivered. Treat as a failure (go through backoff),
		// so this delivery is not claimed again and again and never gets marked.
		err = fmt.Errorf(errDeliveryNoDeliveredCount, delivered)
	}

	// The failure handling is decided **per item**, not from the maximum attempt count of the whole batch.
	//
	// It used to be `if maxAttempts(deliveries) >= MaxNotifyAttempts` and the whole batch was declared dead, but
	// the attempt counts within a batch differ: an old delivery that has already retried twice (attempts=2) would drag the brand-new deliveries
	// of the same batch (attempts=1) into failed with it. A new vulnerability would be lost permanently without using a single retry,
	// which is the opposite of the intent that "old rows must not drag new rows down".
	permanent := notify.IsPermanent(err)
	var failIDs, exhaustedIDs []int64
	byDelay := map[time.Duration][]int64{}
	for _, dl := range deliveries {
		switch {
		case permanent:
			failIDs = append(failIDs, dl.ID)
		case dl.Attempts >= db.MaxNotifyAttempts:
			exhaustedIDs = append(exhaustedIDs, dl.ID)
		default:
			delay := notifyBackoff[min(dl.Attempts, len(notifyBackoff)-1)]
			byDelay[delay] = append(byDelay[delay], dl.ID)
		}
	}

	if len(failIDs) > 0 {
		if fErr := n.pg.FailDeliveries(ctx, failIDs, err.Error()); fErr != nil {
			log.Printf("[notify] failed to mark failure state channel=%s ids=%v: %v", channel.Kind(), failIDs, fErr)
		}
	}
	if len(exhaustedIDs) > 0 {
		reason := fmt.Sprintf(errDeliveryRetryExhausted, db.MaxNotifyAttempts, err)
		if fErr := n.pg.FailDeliveries(ctx, exhaustedIDs, reason); fErr != nil {
			log.Printf("[notify] failed to mark failure state channel=%s ids=%v: %v", channel.Kind(), exhaustedIDs, fErr)
		}
	}
	// Reschedule grouped by delay: there are only 3 backoff tiers, so the number of groups is naturally small, and there is no need to send
	// one UPDATE per item (that would make a batch of 500 cost 500 round trips).
	for delay, group := range byDelay {
		if rErr := n.pg.RescheduleDeliveries(ctx, group, delay, err.Error()); rErr != nil {
			log.Printf("[notify] failed to requeue deliveries channel=%s ids=%v: %v", channel.Kind(), group, rErr)
		}
	}
	if len(failIDs)+len(exhaustedIDs) > 0 {
		log.Printf("[notify] delivery failed channel=%d kind=%s permanent=%d retries_exhausted=%d pending_retry=%d: %s",
			deliveries[0].ChannelID, channel.Kind(), len(failIDs), len(exhaustedIDs), len(byDelay), err)
	}
}

// excludeDeliveries returns the items of all that are not in keep (compared by pointer identity).
// Used to find the deliveries that "did not make it into the message": they must be handled explicitly and must not be left in a gray area.
func excludeDeliveries(all, keep []*db.NotificationDelivery) []*db.NotificationDelivery {
	inKeep := make(map[*db.NotificationDelivery]bool, len(keep))
	for _, dl := range keep {
		inKeep[dl] = true
	}
	var out []*db.NotificationDelivery
	for _, dl := range all {
		if !inKeep[dl] {
			out = append(out, dl)
		}
	}
	return out
}

// adapt gets the channel implementation and parses its configuration.
// Returning ok=false means the type is not registered; the delivery should be failed directly instead of retried forever.
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// If config parsing fails, use an empty map: the channel's own Validate reports which field is missing,
		// and that error guides the user to a fix better than a JSON parse error.
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle renders a single-vulnerability message.
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch renders a digest message. It parses snapshots one by one: if one is broken, only that one is skipped,
// so it cannot take down the whole digest.
//
// The returned included corresponds **strictly one to one** with msg.Items (delivery i <-> item i).
// This correspondence is a hard requirement: the caller uses "the channel reported that the first K fit" to decide that the first K deliveries
// are marked delivered. If a bad snapshot is skipped here without removing its delivery from included,
// the indexes shift: an entry that should fail is marked delivered, and a good entry is wrongly judged undelivered.
// The caller marks the broken ones as failed explicitly, see stepDigest.
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, []*db.NotificationDelivery, error) {
	items := make([]notify.Item, 0, len(deliveries))
	included := make([]*db.NotificationDelivery, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			// A bad snapshot goes into neither the message nor included; handling it is the caller's job
			// (mark it failed explicitly instead of letting it slip through among the "delivered").
			log.Printf("[notify] skipped unparsable snapshot in digest batch delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, nil, err
		}
		items = append(items, item)
		included = append(included, dl)
	}
	if len(items) == 0 {
		return notify.Message{}, nil, fmt.Errorf(errDeliveryBatchAllUnparseable, len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, included, nil
}

// itemFor renders an event snapshot into an item to push, also resolving the asset name and the detail backlink.
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// A failure to resolve the asset name must not block the push: not being able to read a name is far less serious than not receiving the notification;
		// the message just lacks one asset line.
		log.Printf("[notify] failed to resolve asset name finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// For the detail page route see web/src/app/(main)/function/findings/detail/page.tsx;
		// it reads the vulnerability id from the query parameter id.
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens takes **at most want** tokens from the channel's token bucket and returns the number actually taken.
//
// One token = one message (one HTTP request). In realtime mode the caller passes as many as it needs;
// in digest mode a whole batch of vulnerabilities is sent as one message, so pass 1.
//
// The bucket capacity is the per-minute limit of the channel, refilled at a constant rate. ratePerMin<=0 means no rate limit,
// and a finite but large enough value is returned, so one round of the loop is not held up by an unbounded backlog.
//
// The want cap is required: without it the only option is to drain the whole bucket, while the caller has its own per-round cap.
// The extra tokens would be useless and would vanish before the next refill: the accumulated burst capacity could never be reached,
// and even a round with no pending deliveries would still be charged.
func (n *Notifier) takeTokens(channelID int64, ratePerMin, want int, now time.Time) int {
	if want <= 0 {
		return 0
	}
	if ratePerMin <= 0 {
		return min(want, notifyUnlimitedBurstPerTick)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// Refill according to the real elapsed time, at a rate of ratePerMin/60 per second.
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// Add a tiny epsilon before truncating to an integer: the token count is accumulated in floating point, so when refilled in two steps
	// 0.5 + 0.5 may give 0.9999999999, and a plain int() truncates it to 0,
	// so a bucket that is mathematically full yields no token. 1e-9 is far below one token and does not let a real shortfall through.
	take := min(int(b.tokens+1e-9), want)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled reads the master switch.
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL returns the external address used for backlinks, with the trailing slash removed.
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval returns the digest interval, falling back to the default when invalid or not configured.
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot parses the event snapshot belonging to a delivery.
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf(errDeliverySnapshotEmpty, dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf(errDeliverySnapshotParse, dl.ID, err)
	}
	if snap.Kind == "" {
		// The event kind follows the event row; the one in the snapshot may have been written by an older version.
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
