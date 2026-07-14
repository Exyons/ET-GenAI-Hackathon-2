import { TelemetryConsole, type TelemetryView } from "../../components/TelemetryConsole";

export const dynamic = "force-dynamic";

export default async function TelemetryPage({
  searchParams,
}: {
  searchParams: Promise<{ view?: string }>;
}) {
  const { view } = await searchParams;
  const initial: TelemetryView = view === "flagged" ? "flagged" : "recent";
  return (
    <main className="wrap">
      <TelemetryConsole initialView={initial} />
    </main>
  );
}
