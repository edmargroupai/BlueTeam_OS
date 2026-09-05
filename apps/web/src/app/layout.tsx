import type { Metadata } from "next";
import "../styles/globals.css";

export const metadata: Metadata = {
  title: "Blue Team OS Center",
  description: "Defensive cybersecurity operating system",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
