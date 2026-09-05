import type { Meta, StoryObj } from "@storybook/react";
import { MetricTile, Grid, DataTable } from "@/components/ui/Primitives";
import { StateBox } from "@/components/AppShell";

const meta: Meta = {
  title: "Primitives/Foundation",
};

export default meta;

type Story = StoryObj;

export const Metrics: Story = {
  render: () => (
    <Grid cols={4}>
      <MetricTile label="Open alerts" value={12} />
      <MetricTile label="Findings" value={48} />
      <MetricTile label="Quality" value={712} />
      <MetricTile label="Band" value="lab" />
    </Grid>
  ),
};

export const States: Story = {
  render: () => (
    <div style={{ display: "grid", gap: 12 }}>
      <StateBox kind="loading" text="Loading…" />
      <StateBox kind="empty" text="No rows yet." />
      <StateBox kind="error" text="Upstream failed." />
      <StateBox kind="disabled" text="Feature gated." />
    </div>
  ),
};

export const Table: Story = {
  render: () => (
    <DataTable
      columns={[
        { key: "sev", label: "Severity", mono: true },
        { key: "title", label: "Title" },
      ]}
      rows={[
        { sev: "high", title: "Repeated auth failures" },
        { sev: "medium", title: "New admin role assigned" },
      ]}
    />
  ),
};
