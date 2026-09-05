import type { Preview } from "@storybook/react";
import "../src/styles/globals.css";

const preview: Preview = {
  parameters: {
    layout: "padded",
    backgrounds: {
      default: "btos",
      values: [{ name: "btos", value: "#0B0E14" }],
    },
    a11y: { test: "todo" },
  },
};

export default preview;
