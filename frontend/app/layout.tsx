import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "Secure SaaS Starter by Adekunle Akeju",
  description: "A SaaS starter with MFA, roles, audit logs and tenant isolation, created by Adekunle Akeju.",
  authors: [{ name: "Adekunle Akeju" }],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
