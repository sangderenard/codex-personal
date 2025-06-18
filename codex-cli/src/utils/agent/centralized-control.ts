import type { ToolDefinition, ResponseItemDefinition } from './agent-loop';
import type { AppConfig } from '../config';

export class CentralizedControl {
  private config: AppConfig;

  constructor(config: AppConfig) {
    this.config = config;
  }

  private async fetchPolicyApproval(tool: ToolDefinition): Promise<boolean> {
    // Delegate policy approval to the Rust backend
    const response = await fetch(`/policy-watcher/approve?tool=${tool.type}`);
    return response.ok;
  }

  public async execute(tool: ToolDefinition, args: any): Promise<ResponseItemDefinition> {
    const approved = await this.fetchPolicyApproval(tool);
    if (!approved) {
      throw new Error('Execution not approved');
    }

    const result: ResponseItemDefinition = await tool.execute(args);
    return result;
  }
}
