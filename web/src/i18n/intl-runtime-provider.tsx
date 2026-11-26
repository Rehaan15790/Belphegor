"use client";

import type { ReactNode } from "react";

import { NextIntlClientProvider } from "next-intl";

import messages from "../../messages/en.json";

// Passed explicitly: without a time zone next-intl logs ENVIRONMENT_FALLBACK while prerendering.
const TIME_ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

export function IntlRuntimeProvider({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <NextIntlClientProvider locale="en" messages={messages} timeZone={TIME_ZONE}>
      {children}
    </NextIntlClientProvider>
  );
}
