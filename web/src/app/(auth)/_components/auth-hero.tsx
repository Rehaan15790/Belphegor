import { useTranslations } from "next-intl";

import { Wordmark } from "@/components/wordmark";

// Brand panel on the left of the login and setup pages. The "dark" class keeps it
// black with the dark palette even when the app runs in light mode.
export function AuthHero() {
  const t = useTranslations("auth.brand");
  return (
    <div className="dark relative hidden flex-col justify-center gap-6 overflow-hidden border-r border-primary/25 bg-background px-14 text-foreground lg:flex lg:w-1/2">
      <div aria-hidden className="absolute -top-10 -right-28 h-[150%] w-64 rotate-[18deg] bg-primary/[0.07]" />
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="/logo.svg"
        alt=""
        width={120}
        height={120}
        className="relative drop-shadow-[0_0_10px_rgb(255_30_45/0.55)]"
      />
      <Wordmark className="relative text-5xl leading-none xl:text-6xl [&>span]:[text-shadow:0_0_22px_rgb(255_30_45/0.5)]" />
      <p className="relative text-sm font-semibold uppercase tracking-[0.32em] text-muted-foreground">
        {t("tagline")}
      </p>
      <div className="absolute inset-x-0 bottom-0 flex h-8 items-center bg-[repeating-linear-gradient(-45deg,var(--primary)_0_12px,var(--background)_12px_24px)] pl-14">
        <span className="bg-background px-3 py-1 text-[11px] font-bold uppercase tracking-[0.26em] text-primary">
          {t("authorizedOnly")}
        </span>
      </div>
    </div>
  );
}
