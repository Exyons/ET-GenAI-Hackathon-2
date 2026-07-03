export const metadata = { title: "Prahari SOC", description: "Cyber resilience command center" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ background: "#0a0e14", color: "#e6edf3", fontFamily: "monospace", margin: 0 }}>
        {children}
      </body>
    </html>
  );
}
