import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";

export const metadata: Metadata = {
  title: "Fenrir Security Console",
  description: "Incident-led Windows endpoint protection and security operations console",
  icons: {
    icon: [
      { url: "/fenrir.ico", rel: "icon" },
      { url: "/fenrir.png", type: "image/png" }
    ],
    apple: "/fenrir.png"
  }
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
