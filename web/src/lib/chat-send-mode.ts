"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { getLocalStorageValue, setLocalStorageValue } from "@/lib/local-storage.client";

// Key combination for sending / inserting a newline in the session input box. It is a pure frontend preference, so it is stored only in localStorage,
// not on the server, and is not synced with the account. Hence it must be set again when switching browsers.
// See issue #39: 0.3.2 changed Ctrl+Enter to send into Enter to send,
// and here the old key combination is restored as an option.
export type ChatSendMode = "enter" | "ctrl-enter";

export const CHAT_SEND_MODE_KEY = "belphegor_chat_send_mode";
export const DEFAULT_CHAT_SEND_MODE: ChatSendMode = "enter";

// Options for the send-mode dropdown on the settings screen. Labels depend on the locale, so they are returned from a hook
// rather than a module constant. value is a stable identifier, used as is for the localStorage key and behavior checks.
export function useChatSendModeOptions(): { value: ChatSendMode; label: string }[] {
  const t = useTranslations("chatSendMode.option");
  return [
    { value: "enter", label: t("enter") },
    { value: "ctrl-enter", label: t("ctrlEnter") },
  ];
}

function parseMode(raw: string | null): ChatSendMode {
  return raw === "ctrl-enter" || raw === "enter" ? raw : DEFAULT_CHAT_SEND_MODE;
}

// Set of subscribers within the same tab. The localStorage storage event fires only in "other" tabs,
// so after changing the setting in the current tab, emit must notify this tab's input box.
// Otherwise the change only shows after a refresh.
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
}

// Returns a string literal, so Object.is compares by value and useSyncExternalStore does not
// fall into an infinite loop.
function getSnapshot(): ChatSendMode {
  return parseMode(getLocalStorageValue(CHAT_SEND_MODE_KEY));
}

// The server has no localStorage, so render the default first; after hydration getSnapshot
// corrects the value.
function getServerSnapshot(): ChatSendMode {
  return DEFAULT_CHAT_SEND_MODE;
}

export function useChatSendMode(): ChatSendMode {
  return React.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

export function setChatSendMode(mode: ChatSendMode) {
  setLocalStorageValue(CHAT_SEND_MODE_KEY, mode);
  for (const listener of listeners) listener();
}

// shouldSubmitOnKey decides whether a single key press counts as a send.
// isComposing / keyCode 229 means an input method (Korean, Chinese, etc.) is composing text,
// so it must always pass through. Otherwise confirming a character with Enter would send by mistake.
// enter mode excludes only Shift, keeping exactly the same behavior as 0.3.2, down to the last
// detail (the feel does not change for users who never changed the setting). ctrl-enter mode
// accepts both Ctrl and Cmd (macOS).
export function shouldSubmitOnKey(e: React.KeyboardEvent, mode: ChatSendMode): boolean {
  if (e.key !== "Enter") return false;
  if (e.nativeEvent.isComposing || e.nativeEvent.keyCode === 229) return false;
  if (mode === "ctrl-enter") return e.ctrlKey || e.metaKey;
  return !e.shiftKey;
}
