import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Belphegor",
  version: packageJson.version,
  copyright: `© ${currentYear}, Belphegor.`,
  meta: {
    title: "Belphegor: Autonomous Penetration Testing Console",
    description: "An LLM-driven system console for autonomous penetration testing",
  },
};
