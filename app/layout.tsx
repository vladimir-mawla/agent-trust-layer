import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "agent-trust-layer",
  description:
    "A verifiable trust layer for AI agents: self-certifying identity, credentials, revocation, and explainable policy. Under construction.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
