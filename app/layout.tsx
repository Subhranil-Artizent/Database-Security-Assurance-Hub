import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

function safeRequestHost(value: string): string {
  if (!/^[a-z0-9.-]+(?::\d{1,5})?$/i.test(value)) return "localhost:3000";
  try {
    return new URL(`https://${value}`).host;
  } catch {
    return "localhost:3000";
  }
}

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const requestedHost =
    requestHeaders.get("x-forwarded-host") ??
    requestHeaders.get("host") ??
    "localhost:3000";
  const host = safeRequestHost(requestedHost);
  const protocol = host.startsWith("localhost") ? "http" : "https";

  return {
    metadataBase: new URL(`${protocol}://${host}`),
    title: "AegisDB | Database Security Assurance",
    description:
      "Secure Oracle, PostgreSQL, Sybase, and MySQL with a practical assurance program for encryption, data protection, access security, and masking.",
    icons: {
      icon: "/favicon.png",
      shortcut: "/favicon.png",
    },
    openGraph: {
      title: "Secure every database. | AegisDB",
      description:
        "Turn database security priorities into an actionable control roadmap across Oracle, PostgreSQL, Sybase, and MySQL.",
      images: [{ url: "/og.png", width: 1200, height: 630 }],
      type: "website",
    },
    twitter: {
      card: "summary_large_image",
      title: "Secure every database. | AegisDB",
      description:
        "Database security assurance across Oracle, PostgreSQL, Sybase, and MySQL.",
      images: ["/og.png"],
    },
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
