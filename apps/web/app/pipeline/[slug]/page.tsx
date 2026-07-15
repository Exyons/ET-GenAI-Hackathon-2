import { notFound } from "next/navigation";

import { StageDetail } from "../../../components/StageDetail";
import { STAGE_BY_SLUG, type StageSlug } from "../../../lib/pipeline";

export const dynamic = "force-dynamic";

export default async function PipelineStagePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!STAGE_BY_SLUG[slug]) notFound();
  return (
    <main className="wrap">
      <StageDetail slug={slug as StageSlug} />
    </main>
  );
}
