/**
 * CORD Framework Adapters — Unified exports
 *
 * Usage:
 *   const cord = require("cord-engine");
 *
 *   // LangChain
 *   const model = cord.frameworks.wrapLangChain(new ChatOpenAI());
 *   const chain = cord.frameworks.wrapChain(myChain);
 *   const tool  = cord.frameworks.wrapTool(myTool);
 *
 *   // CrewAI
 *   const agent = cord.frameworks.wrapCrewAgent(myCrewAgent);
 *
 *   // AutoGen
 *   const agent = cord.frameworks.wrapAutoGenAgent(myAutoGenAgent);
 */

const { wrapLangChain, wrapChain, wrapTool } = require("./langchain");
const { wrapCrewAgent } = require("./crewai");
const { wrapAutoGenAgent } = require("./autogen");

module.exports = {
  // LangChain
  wrapLangChain,
  wrapChain,
  wrapTool,

  // CrewAI
  wrapCrewAgent,

  // AutoGen
  wrapAutoGenAgent,
};
