import type { ReservoirLimiter } from './rateLimiter';
import type { OpenAI } from "openai";
import type {
  ResponseCreateParams,
  Response,
} from "openai/resources/responses/responses";

import { FrameMessenger } from './FrameMessenger';
import { createRateLimiter } from './rateLimiter';
import winston from 'winston';

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'responses.log' })
  ]
});

// Define interfaces based on OpenAI API documentation
type ResponseCreateInput = ResponseCreateParams;
type ResponseOutput = Response;
// interface ResponseOutput {
//   id: string;
//   object: 'response';
//   created_at: number;
//   status: 'completed' | 'failed' | 'in_progress' | 'incomplete';
//   error: { code: string; message: string } | null;
//   incomplete_details: { reason: string } | null;
//   instructions: string | null;
//   max_output_tokens: number | null;
//   model: string;
//   output: Array<{
//     type: 'message';
//     id: string;
//     status: 'completed' | 'in_progress';
//     role: 'assistant';
//     content: Array<{
//       type: 'output_text' | 'function_call';
//       text?: string;
//       annotations?: Array<any>;
//       tool_call?: {
//         id: string;
//         type: 'function';
//         function: { name: string; arguments: string };
//       };
//     }>;
//   }>;
//   parallel_tool_calls: boolean;
//   previous_response_id: string | null;
//   reasoning: { effort: string | null; summary: string | null };
//   store: boolean;
//   temperature: number;
//   text: { format: { type: 'text' } };
//   tool_choice: string | object;
//   tools: Array<any>;
//   top_p: number;
//   truncation: string;
//   usage: {
//     input_tokens: number;
//     input_tokens_details: { cached_tokens: number };
//     output_tokens: number;
//     output_tokens_details: { reasoning_tokens: number };
//     total_tokens: number;
//   } | null;
//   user: string | null;
//   metadata: Record<string, string>;
// }

// Define types for the ResponseItem content and parts
type ResponseContentPart = {
  type: string;
  [key: string]: unknown;
};

type ResponseItemType = {
  type: string;
  id?: string;
  status?: string;
  role?: string;
  content?: Array<ResponseContentPart>;
  [key: string]: unknown;
};

type ResponseEvent =
  | { type: "response.created"; response: Partial<ResponseOutput> }
  | { type: "response.in_progress"; response: Partial<ResponseOutput> }
  | {
      type: "response.output_item.added";
      output_index: number;
      item: ResponseItemType;
    }
  | {
      type: "response.content_part.added";
      item_id: string;
      output_index: number;
      content_index: number;
      part: ResponseContentPart;
    }
  | {
      type: "response.output_text.delta";
      item_id: string;
      output_index: number;
      content_index: number;
      delta: string;
    }
  | {
      type: "response.output_text.done";
      item_id: string;
      output_index: number;
      content_index: number;
      text: string;
    }
  | {
      type: "response.function_call_arguments.delta";
      item_id: string;
      output_index: number;
      content_index: number;
      delta: string;
    }
  | {
      type: "response.function_call_arguments.done";
      item_id: string;
      output_index: number;
      content_index: number;
      arguments: string;
    }
  | {
      type: "response.content_part.done";
      item_id: string;
      output_index: number;
      content_index: number;
      part: ResponseContentPart;
    }
  | {
      type: "response.output_item.done";
      output_index: number;
      item: ResponseItemType;
    }
  | { type: "response.completed"; response: ResponseOutput }
  | { type: "error"; code: string; message: string; param: string | null };

// Define a type for tool call data
type ToolCallData = {
  id: string;
  name: string;
  arguments: string;
};

// Define a type for usage data
type UsageData = {
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
  input_tokens?: number;
  input_tokens_details?: { cached_tokens: number };
  output_tokens?: number;
  output_tokens_details?: { reasoning_tokens: number };
  [key: string]: unknown;
};

// Define a type for content output
type ResponseContentOutput =
  | {
      type: "function_call";
      call_id: string;
      name: string;
      arguments: string;
      [key: string]: unknown;
    }
  | {
      type: "output_text";
      text: string;
      annotations: Array<unknown>;
      [key: string]: unknown;
    };

// Global map to store conversation histories
const conversationHistories = new Map<
  string,
  {
    previous_response_id: string | null;
    messages: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>;
  }
>();

// Utility function to generate unique IDs
function generateId(prefix: string = "msg"): string {
  return `${prefix}_${Math.random().toString(36).substr(2, 9)}`;
}

// Function to convert ResponseInputItem to ChatCompletionMessageParam
type ResponseInputItem = ResponseCreateInput["input"][number];

function convertInputItemToMessage(
  item: string | ResponseInputItem,
): OpenAI.Chat.Completions.ChatCompletionMessageParam {
  // Handle string inputs as content for a user message
  if (typeof item === "string") {
    return { role: "user", content: item };
  }

  // At this point we know it's a ResponseInputItem
  const responseItem = item;

  if (responseItem.type === "message") {
    // Use a more specific type assertion for the message content
    const content = Array.isArray(responseItem.content)
      ? responseItem.content
          .filter((c) => typeof c === "object" && c.type === "input_text")
          .map((c) =>
            typeof c === "object" && "text" in c
              ? (c["text"] as string) || ""
              : "",
          )
          .join("")
      : "";
    return { role: responseItem.role, content };
  } else if (responseItem.type === "function_call_output") {
    return {
      role: "tool",
      tool_call_id: responseItem.call_id,
      content: responseItem.output,
    };
  }
  throw new Error(`Unsupported input item type: ${responseItem.type}`);
}

// Function to get full messages including history
function getFullMessages(
  input: ResponseCreateInput,
): Array<OpenAI.Chat.Completions.ChatCompletionMessageParam> {
  let baseHistory: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam> =
    [];
  if (input.previous_response_id) {
    const prev = conversationHistories.get(input.previous_response_id);
    if (!prev) {
      throw new Error(
        `Previous response not found: ${input.previous_response_id}`,
      );
    }
    baseHistory = prev.messages;
  }

  // Handle both string and ResponseInputItem in input.input
  const newInputMessages = Array.isArray(input.input)
    ? input.input.map(convertInputItemToMessage)
    : [convertInputItemToMessage(input.input)];

  const messages = [...baseHistory, ...newInputMessages];
  if (
    input.instructions &&
    messages[0]?.role !== "system" &&
    messages[0]?.role !== "developer"
  ) {
    return [{ role: "system", content: input.instructions }, ...messages];
  }
  return messages;
}

// Function to convert tools
function convertTools(
  tools?: ResponseCreateInput["tools"],
): Array<OpenAI.Chat.Completions.ChatCompletionTool> | undefined {
  return tools
    ?.filter((tool) => tool.type === "function")
    .map((tool) => ({
      type: "function" as const,
      function: {
        name: tool.name,
        description: tool.description || undefined,
        parameters: tool.parameters,
      },
    }));
}

// --- Provider abstraction and windowing skeletons ---

/**
 * Utility to window/prune messages to fit a model's token limit.
 * This should use a tokenizer for the target model and trim/prune/merge as needed.
 * For now, this is a stub.
 */
function estimateTokensForMessages(
  messages: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>,
  charsPerToken = 4
): number {
  // Simple heuristic: count total chars, divide by charsPerToken
  const totalChars = messages.reduce((sum, m) => {
    let contentLength = 0;
    if (typeof m.content === "string") {
      contentLength = m.content.length;
    } else if (Array.isArray(m.content)) {
      const validatedContent = (m.content as Array<unknown>).map((c) => {
        if (typeof c === "string") {
          return ensureNumber(c.length);
        }
        if (typeof c === "object" && c !== null && "text" in c && typeof (c as { text: unknown }).text === "string") {
          return ensureNumber((c as { text: string }).text.length);
        }
        return 0; // Default fallback
      });
      contentLength = validatedContent.reduce((acc, length) => acc + length, 0);
    }
    return sum + contentLength;
  }, 0);
  return Math.ceil(totalChars / charsPerToken);
}

function windowMessagesForModel(
  messages: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>,
  model: string, // TODO: Use for model-specific windowing
  maxTokens: number // TODO: Use for token limit
): Array<OpenAI.Chat.Completions.ChatCompletionMessageParam> {
  void model; // suppress unused warning
  void maxTokens; // suppress unused warning
  // Estimate tokens and trim from the start if needed
  const windowed = [...messages];
  while (estimateTokensForMessages(windowed) > maxTokens && windowed.length > 1) {
    windowed.shift(); // Remove oldest message
  }
  return windowed;
}

/**
 * Splits messages into windows that fit within the token limit.
 * Returns an array of message arrays (windows).
 */
function splitMessagesIntoWindows(
  messages: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>,
  model: string,
  maxTokens: number
): Array<Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>> {
  const windows: Array<Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>> = [];
  let current: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam> = [];
  for (const msg of messages) {
    current.push(msg);
    if (estimateTokensForMessages(current) > maxTokens) {
      // Remove the last message, start a new window
      current.pop();
      if (current.length > 0) {windows.push(current);}
      current = [msg];
    }
  }
  if (current.length > 0) {windows.push(current);}
  return windows;
}

/**
 * Sends each window as a separate API call, with framing instructions.
 * After all windows, sends a final synthesis prompt.
 * Allows custom frame header/footer and rate limiting.
 */
async function sendFramedWindows(
  provider: ChatCompletionProvider,
  baseMessages: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>,
  model: string,
  maxTokens: number,
  options: any,
  rateLimiter?: ReservoirLimiter,
  frameMessenger?: FrameMessenger,
): Promise<any> {
  const windows = splitMessagesIntoWindows(baseMessages, model, maxTokens);
  logger.info('Starting framed window processing', { totalWindows: windows.length });

  for (let i = 0; i < windows.length; ++i) {
    const headerMsg = ({
      role: "system",
      content: frameMessenger?.getHeader(i, windows.length)
    } as OpenAI.Chat.Completions.ChatCompletionSystemMessageParam);
    const footerMsg = ({
      role: "system",
      content: frameMessenger?.getFooter(i, windows.length)
    } as OpenAI.Chat.Completions.ChatCompletionSystemMessageParam);

    const windowWithFrame: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam> = [headerMsg, ...windows[i]!];
    windowWithFrame.push(footerMsg);

    const chunkTokens = estimateTokensForMessages(windowWithFrame, 4);
    logger.info('Processing chunk', { chunkIndex: i + 1, totalChunks: windows.length, tokens: chunkTokens });

    if (rateLimiter) {
      await rateLimiter.schedule({ weight: chunkTokens }, () => Promise.resolve());
    }

    try {
      // eslint-disable-next-line no-await-in-loop
      await provider.createChatCompletion(windowWithFrame, options);
      logger.info('Chunk processed successfully', { chunkIndex: i + 1 });
    } catch (error: any) { // Explicitly type `error` as `any` or `Error`
      logger.error('Error processing chunk', { chunkIndex: i + 1, error: error.message });
      throw error;
    }
  }

  const finalMsg: OpenAI.Chat.Completions.ChatCompletionMessageParam = {
    role: "system",
    content: frameMessenger?.getInstructions(windows.length, windows.length)
  } as OpenAI.Chat.Completions.ChatCompletionSystemMessageParam;

  const allMessages: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam> = [finalMsg, ...baseMessages];
  const finalTokens = estimateTokensForMessages(allMessages, 4);
  logger.info('Sending final synthesis message', { tokens: finalTokens });

  if (rateLimiter) {
    await rateLimiter.schedule({ weight: finalTokens }, () => Promise.resolve());
  }

  try {
    return provider.createChatCompletion(allMessages, options);
  } catch (error: any) { // Explicitly type `error` as `any` or `Error`
    logger.error('Error during final synthesis', { error: error.message });
    throw error;
  }
}

/**
 * Abstracted chat completion provider interface.
 */
interface ChatCompletionProvider {
  createChatCompletion(
    messages: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>,
    options: {
      model: string;
      tools?: any;
      temperature?: number;
      top_p?: number;
      tool_choice?: any;
      stream?: boolean;
      user?: string;
      metadata?: any;
      maxTokens?: number;
    }
  ): Promise<any>;
}

/**
 * OpenAI provider implementation (skeleton).
 */
class OpenAIProvider implements ChatCompletionProvider {
  constructor(private openai: OpenAI) {}
  async createChatCompletion(
    messages: Array<OpenAI.Chat.Completions.ChatCompletionMessageParam>,
    options: {
      model: string;
      tools?: any;
      temperature?: number;
      top_p?: number;
      tool_choice?: any;
      stream?: boolean;
      user?: string;
      metadata?: any;
      maxTokens?: number;
    }
  ): Promise<any> {
    // TODO: Add windowing here if needed
    return this.openai.chat.completions.create({
      model: options.model,
      messages,
      tools: options.tools,
      temperature: options.temperature,
      top_p: options.top_p,
      tool_choice: options.tool_choice,
      stream: options.stream,
      user: options.user,
      metadata: options.metadata,
    });
  }
}

function getProvider(provider: string, openai: OpenAI): ChatCompletionProvider {
  // TODO: Add Gemini, Claude, etc. here
  if (!provider || provider.toLowerCase() === "openai") {
    return new OpenAIProvider(openai);
  }
  throw new Error(`Unknown provider: ${provider}`);
}

// --- Refactored createCompletion to use provider abstraction and windowing ---

const createCompletion = (
  openai: OpenAI,
  input: ResponseCreateInput,
  providerName: string = "openai"
) => {
  const fullMessages = getFullMessages(input);
  const chatTools = convertTools(input.tools);
  // Window messages before sending to provider
  const windowedMessages = windowMessagesForModel(
    fullMessages,
    input.model,
    4096 // TODO: Use model-specific max tokens
  );
  const provider = getProvider(providerName, openai);
  return provider.createChatCompletion(windowedMessages, {
    model: input.model,
    tools: chatTools,
    temperature: input.temperature ?? undefined,
    top_p: input.top_p ?? undefined,
    tool_choice: input.tool_choice === "auto"
      ? "auto"
      : input.tool_choice,
    stream: input.stream || false,
    user: input.user,
    metadata: input.metadata,
    maxTokens: 4096, // TODO: Use model-specific max tokens
  });
};

// Main function with overloading
async function responsesCreateViaChatCompletions(
  openai: OpenAI,
  input: ResponseCreateInput & { stream: true },
  rateLimiter?: ReservoirLimiter,
): Promise<AsyncGenerator<ResponseEvent>>;
async function responsesCreateViaChatCompletions(
  openai: OpenAI,
  input: ResponseCreateInput & { stream?: false },
  rateLimiter?: ReservoirLimiter,
): Promise<ResponseOutput>;
async function responsesCreateViaChatCompletions(
  openai: OpenAI,
  input: ResponseCreateInput,
  rateLimiter?: ReservoirLimiter,
  rateLimiterConfig?: {
    TPM: number; // Tokens per minute
    RPM: number; // Requests per minute
    INTERVAL?: number; // Interval in milliseconds for refreshing tokens
    MARGIN?: number; // Margin to prevent overuse
  }
): Promise<ResponseOutput | AsyncGenerator<ResponseEvent>> {
  logger.info('Starting response creation', { inputModel: input.model });

  let currentRateLimiter: ReservoirLimiter;
  if (rateLimiter) {
    currentRateLimiter = rateLimiter;
  } else {
    const {
      TPM = 30000, // Default: 30,000 tokens per minute
      RPM = 500, // Default: 500 requests per minute
      INTERVAL = 120, // Default: Refresh every 120ms
      MARGIN = 0.9, // Default: 90% margin
    } = rateLimiterConfig || {};

    currentRateLimiter = createRateLimiter(TPM, RPM, INTERVAL, MARGIN);
  }

  // Log the reservoir size whenever tokens are consumed
  logger.info('Rate limiter reservoir updated', {
    reservoirSize: currentRateLimiter.getLastReservoir(),
  });

  // --- Windowing/Chunking Orchestration ---
  const fullMessages = getFullMessages(input);
  const maxTokens = 4096;
  const estimatedTokens = estimateTokensForMessages(fullMessages, 4);
  const provider = getProvider("openai", openai);
  const options = {
    model: input.model,
    tools: convertTools(input.tools),
    temperature: input.temperature ?? undefined,
    top_p: input.top_p ?? undefined,
    tool_choice: input.tool_choice === "auto" ? "auto" : input.tool_choice,
    stream: input.stream || false,
    user: input.user,
    metadata: input.metadata,
    maxTokens,
  };

  if (estimatedTokens > maxTokens) {
    const messenger = new FrameMessenger(__dirname);
    logger.info('Using chunked windowing', { estimatedTokens, maxTokens });

    return sendFramedWindows(
      provider,
      fullMessages,
      input.model,
      maxTokens,
      options,
      currentRateLimiter,
      messenger,
    );
  }

  try {
    const completion = await createCompletion(openai, input);
    logger.info('Response created successfully', { model: input.model });
    return input.stream
      ? streamResponses(input, completion as AsyncIterable<OpenAI.ChatCompletionChunk>, currentRateLimiter)
      : nonStreamResponses(input, completion as unknown as OpenAI.Chat.Completions.ChatCompletion, currentRateLimiter);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error('Error during response creation', { error: errorMessage });
    throw error;
  }
}

// Non-streaming implementation
async function nonStreamResponses(
  input: ResponseCreateInput,
  completion: OpenAI.Chat.Completions.ChatCompletion,
  rateLimiter: ReservoirLimiter,
): Promise<ResponseOutput> {
  const fullMessages = getFullMessages(input);

  try {
    const chatResponse = completion;
    if (!("choices" in chatResponse) || chatResponse.choices.length === 0) {
      throw new Error("No choices in chat completion response");
    }
    const assistantMessage = chatResponse.choices?.[0]?.message;
    if (!assistantMessage) {
      throw new Error("No assistant message in chat completion response");
    }

    // Construct ResponseOutput
    const responseId = generateId("resp");
    const outputItemId = generateId("msg");
    const outputContent: Array<ResponseContentOutput> = [];

    // Check if the response contains tool calls
    const hasFunctionCalls =
      assistantMessage.tool_calls && assistantMessage.tool_calls.length > 0;

    if (hasFunctionCalls && assistantMessage.tool_calls) {
      for (const toolCall of assistantMessage.tool_calls) {
        if (toolCall.type === "function") {
          outputContent.push({
            type: "function_call",
            call_id: toolCall.id,
            name: toolCall.function.name,
            arguments: toolCall.function.arguments,
          });
        }
      }
    }

    if (assistantMessage.content) {
      outputContent.push({
        type: "output_text",
        text: assistantMessage.content,
        annotations: [],
      });
    }

    // Create response with appropriate status and properties
    const responseOutput = {
      id: responseId,
      object: "response",
      created_at: Math.floor(Date.now() / 1000),
      status: hasFunctionCalls ? "requires_action" : "completed",
      error: null,
      incomplete_details: null,
      instructions: null,
      max_output_tokens: null,
      model: chatResponse.model,
      output: [
        {
          type: "message",
          id: outputItemId,
          status: "completed",
          role: "assistant",
          content: outputContent,
        },
      ],
      parallel_tool_calls: input.parallel_tool_calls ?? false,
      previous_response_id: input.previous_response_id ?? null,
      reasoning: null,
      temperature: input.temperature,
      text: { format: { type: "text" } },
      tool_choice: input.tool_choice ?? "auto",
      tools: input.tools ?? [],
      top_p: input.top_p,
      truncation: input.truncation ?? "disabled",
      usage: chatResponse.usage
        ? {
            input_tokens: chatResponse.usage.prompt_tokens,
            input_tokens_details: { cached_tokens: 0 },
            output_tokens: chatResponse.usage.completion_tokens,
            output_tokens_details: { reasoning_tokens: 0 },
            total_tokens: chatResponse.usage.total_tokens,
          }
        : undefined,
      user: input.user ?? undefined,
      metadata: input.metadata ?? {},
      output_text: "",
    } as ResponseOutput;

    // Add required_action property for tool calls
    if (hasFunctionCalls && assistantMessage.tool_calls) {
      // Define type with required action
      type ResponseWithAction = Partial<ResponseOutput> & {
        required_action: unknown;
      };

      // Use the defined type for the assertion
      (responseOutput as ResponseWithAction).required_action = {
        type: "submit_tool_outputs",
        submit_tool_outputs: {
          tool_calls: assistantMessage.tool_calls.map((toolCall) => ({
            id: toolCall.id,
            type: toolCall.type,
            function: {
              name: toolCall.function.name,
              arguments: toolCall.function.arguments,
            },
          })),
        },
      };
    }

    // Store history
    const newHistory = [...fullMessages, assistantMessage];
    conversationHistories.set(responseId, {
      previous_response_id: input.previous_response_id ?? null,
      messages: newHistory,
    });

    if (completion.usage) {
      const tokenCount = completion.usage.total_tokens || 0;
      await rateLimiter.schedule({ weight: tokenCount }, () => Promise.resolve());
    } else {
      console.warn("Rate limiter invoked without usage data. Ensure token tracking is accurate.");
    }

    return responseOutput;
  } catch (error: any) { // Explicitly type `error` as `any` or `Error`
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to process chat completion: ${errorMessage}`);
  }
}

// Streaming implementation
async function* streamResponses(
  input: ResponseCreateInput,
  completion: AsyncIterable<OpenAI.ChatCompletionChunk>,
  rateLimiter: ReservoirLimiter,
): AsyncGenerator<ResponseEvent> {
  const fullMessages = getFullMessages(input);

  const responseId = generateId("resp");
  const outputItemId = generateId("msg");
  let textContentAdded = false;
  let textContent = "";
  const toolCalls = new Map<number, ToolCallData>();
  let usage: UsageData | null = null;
  const finalOutputItem: Array<ResponseContentOutput> = [];
  // Initial response
  const initialResponse: Partial<ResponseOutput> = {
    id: responseId,
    object: "response" as const,
    created_at: Math.floor(Date.now() / 1000),
    status: "in_progress" as const,
    model: input.model,
    output: [],
    error: null,
    incomplete_details: null,
    instructions: null,
    max_output_tokens: null,
    parallel_tool_calls: true,
    previous_response_id: input.previous_response_id ?? null,
    reasoning: null,
    temperature: input.temperature,
    text: { format: { type: "text" } },
    tool_choice: input.tool_choice ?? "auto",
    tools: input.tools ?? [],
    top_p: input.top_p,
    truncation: input.truncation ?? "disabled",
    usage: undefined,
    user: input.user ?? undefined,
    metadata: input.metadata ?? {},
    output_text: "",
  };
  yield { type: "response.created", response: initialResponse };
  yield { type: "response.in_progress", response: initialResponse };
  let isToolCall = false;
  for await (const chunk of completion as AsyncIterable<OpenAI.ChatCompletionChunk>) {
    const choice = chunk.choices?.[0];
    if (!choice) {
      continue;
    }
    if (chunk.usage) {
      const tokenCount = chunk.usage.total_tokens || 0;
      await rateLimiter.schedule({ weight: tokenCount }, () => Promise.resolve());
    } else {
      console.warn("Rate limiter invoked without chunk usage data. Ensure token tracking is accurate.");
    }
    if (
      !isToolCall &&
      (("tool_calls" in choice.delta && choice.delta.tool_calls) ||
        choice.finish_reason === "tool_calls")
    ) {
      isToolCall = true;
    }

    if (chunk.usage) {
      usage = {
        prompt_tokens: chunk.usage.prompt_tokens,
        completion_tokens: chunk.usage.completion_tokens,
        total_tokens: chunk.usage.total_tokens,
        input_tokens: chunk.usage.prompt_tokens,
        input_tokens_details: { cached_tokens: 0 },
        output_tokens: chunk.usage.completion_tokens,
        output_tokens_details: { reasoning_tokens: 0 },
      };
    }
    if (isToolCall) {
      for (const tcDelta of choice.delta.tool_calls || []) {
        const tcIndex = tcDelta.index;
        const content_index = textContentAdded ? tcIndex + 1 : tcIndex;

        if (!toolCalls.has(tcIndex)) {
          // New tool call
          const toolCallId = tcDelta.id || generateId("call");
          const functionName = tcDelta.function?.name || "";

          yield {
            type: "response.output_item.added",
            item: {
              type: "function_call",
              id: outputItemId,
              status: "in_progress",
              call_id: toolCallId,
              name: functionName,
              arguments: "",
            },
            output_index: 0,
          };
          toolCalls.set(tcIndex, {
            id: toolCallId,
            name: functionName,
            arguments: "",
          });
        }

        if (tcDelta.function?.arguments) {
          const current = toolCalls.get(tcIndex);
          if (current) {
            current.arguments += tcDelta.function.arguments;
            yield {
              type: "response.function_call_arguments.delta",
              item_id: outputItemId,
              output_index: 0,
              content_index,
              delta: tcDelta.function.arguments,
            };
          }
        }
      }

      if (choice.finish_reason === "tool_calls") {
        for (const [tcIndex, tc] of toolCalls) {
          const item = {
            type: "function_call",
            id: outputItemId,
            status: "completed",
            call_id: tc.id,
            name: tc.name,
            arguments: tc.arguments,
          };
          yield {
            type: "response.function_call_arguments.done",
            item_id: outputItemId,
            output_index: tcIndex,
            content_index: textContentAdded ? tcIndex + 1 : tcIndex,
            arguments: tc.arguments,
          };
          yield {
            type: "response.output_item.done",
            output_index: tcIndex,
            item,
          };
          finalOutputItem.push(item as unknown as ResponseContentOutput);
        }
      } else {
        continue;
      }
    } else {
      if (!textContentAdded) {
        yield {
          type: "response.content_part.added",
          item_id: outputItemId,
          output_index: 0,
          content_index: 0,
          part: { type: "output_text", text: "", annotations: [] },
        };
        textContentAdded = true;
      }
      if (choice.delta.content?.length) {
        yield {
          type: "response.output_text.delta",
          item_id: outputItemId,
          output_index: 0,
          content_index: 0,
          delta: choice.delta.content,
        };
        textContent += choice.delta.content;
      }
      if (choice.finish_reason) {
        yield {
          type: "response.output_text.done",
          item_id: outputItemId,
          output_index: 0,
          content_index: 0,
          text: textContent,
        };
        yield {
          type: "response.content_part.done",
          item_id: outputItemId,
          output_index: 0,
          content_index: 0,
          part: { type: "output_text", text: textContent, annotations: [] },
        };
        const item = {
          type: "message",
          id: outputItemId,
          status: "completed",
          role: "assistant",
          content: [
            { type: "output_text", text: textContent, annotations: [] },
          ],
        };
        yield {
          type: "response.output_item.done",
          output_index: 0,
          item,
        };
        finalOutputItem.push(item as unknown as ResponseContentOutput);
      } else {
        continue;
      }
    }

    // Construct final response
    const finalResponse: ResponseOutput = {
      id: responseId,
      object: "response" as const,
      created_at: initialResponse.created_at || Math.floor(Date.now() / 1000),
      status: "completed" as const,
      error: null,
      incomplete_details: null,
      instructions: null,
      max_output_tokens: null,
      model: chunk.model || input.model,
      output: finalOutputItem as unknown as ResponseOutput["output"],
      parallel_tool_calls: true,
      previous_response_id: input.previous_response_id ?? null,
      reasoning: null,
      temperature: input.temperature,
      text: { format: { type: "text" } },
      tool_choice: input.tool_choice ?? "auto",
      tools: input.tools ?? [],
      top_p: input.top_p,
      truncation: input.truncation ?? "disabled",
      usage: usage as ResponseOutput["usage"],
      user: input.user ?? undefined,
      metadata: input.metadata ?? {},
      output_text: "",
    } as ResponseOutput;

    // Store history
    const assistantMessage: OpenAI.Chat.Completions.ChatCompletionMessageParam =
      {
        role: "assistant" as const,
      };

    if (textContent) {
      assistantMessage.content = textContent;
    }

    // Add tool_calls property if needed
    if (toolCalls.size > 0) {
      const toolCallsArray = Array.from(toolCalls.values()).map((tc) => ({
        id: tc.id,
        type: "function" as const,
        function: { name: tc.name, arguments: tc.arguments },
      }));

      // Define a more specific type for the assistant message with tool calls
      type AssistantMessageWithToolCalls =
        OpenAI.Chat.Completions.ChatCompletionMessageParam & {
          tool_calls: Array<{
            id: string;
            type: "function";
            function: {
              name: string;
              arguments: string;
            };
          }>;
        };

      // Use type assertion with the defined type
      (assistantMessage as AssistantMessageWithToolCalls).tool_calls =
        toolCallsArray;
    }
    const newHistory = [...fullMessages, assistantMessage];
    conversationHistories.set(responseId, {
      previous_response_id: input.previous_response_id ?? null,
      messages: newHistory,
    });

    yield { type: "response.completed", response: finalResponse };
  }
}

function ensureNumber(value: unknown): number {
  if (typeof value === "number") {
    return value;
  }
  throw new Error("Value is not a number");
}


export {
  responsesCreateViaChatCompletions,
  ResponseCreateInput,
  ResponseOutput,
  ResponseEvent,
};
