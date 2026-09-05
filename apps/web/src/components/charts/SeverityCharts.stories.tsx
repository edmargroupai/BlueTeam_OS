import type { Meta, StoryObj } from "@storybook/react";
import { SeverityDonut, RiskBars } from "@/components/charts/SeverityCharts";

const meta: Meta = {
  title: "Charts/Severity",
};

export default meta;

type Story = StoryObj;

export const Donut: Story = {
  render: () => (
    <SeverityDonut
      severity={{ critical: 2, high: 5, medium: 9, low: 14, info: 3 }}
    />
  ),
};

export const EmptyDonut: Story = {
  render: () => <SeverityDonut severity={{}} />,
};

export const Risk: Story = {
  render: () => (
    <RiskBars
      items={[
        { name: "alice", value: 42 },
        { name: "dc-01", value: 31 },
        { name: "vpn-gw", value: 18 },
      ]}
    />
  ),
};
