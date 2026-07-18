import "./globals.css";
import type { Metadata } from "next";
import { Roboto, Roboto_Mono } from "next/font/google";

import { IpModalHost } from "../components/IpModalHost";
import { THEME_SCRIPT } from "../components/ThemeToggle";

const roboto = Roboto({ subsets: ["latin"], weight: ["400", "500", "700"], variable: "--font-roboto" });
const robotoMono = Roboto_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-roboto-mono" });

export const metadata: Metadata = {
  title: "Prahari · Cyber Resilience Command Center",
  description: "Behavioural threat detection for critical national infrastructure",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${roboto.variable} ${robotoMono.variable}`}>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>
        {children}
        <IpModalHost />
      </body>
    </html>
  );
}
