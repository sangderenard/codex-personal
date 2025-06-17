import fs from 'fs';
import path from 'path';

export class FrameMessenger {
	instructions: string;
	header: string;
	footer: string;

	constructor(basePath: string = __dirname) {
		this.header = fs.readFileSync(path.join(basePath, 'frameHeader.md'), 'utf8').trim();
		this.footer = fs.readFileSync(path.join(basePath, 'frameFooter.md'), 'utf8').trim();
		this.instructions = fs.readFileSync(path.join(basePath, 'frameInstructions.md'), 'utf8').trim();
	}

	getHeader(chunk: number, totalChunks: number): string {
		return this.header
			.replace(/\{chunk\}/g, String(chunk + 1))
			.replace(/\{totalChunks\}/g, String(totalChunks));
	}

	getFooter(chunk: number, totalChunks: number): string {
		const isLastChunk = (chunk + 1) === totalChunks;
		const nextPhase = isLastChunk ? "READY FOR SYNTHESIS" : "AWAITING NEXT CHUNK...";
		const progressBar = '█'.repeat(chunk + 1) + '░'.repeat(totalChunks - chunk - 1);
		
		return this.footer
			.replace(/\{chunk\}/g, String(chunk + 1))
			.replace(/\{totalChunks\}/g, String(totalChunks))
			.replace(/\{chunk < totalChunks \? "AWAITING NEXT CHUNK\.\.\." : "READY FOR SYNTHESIS"\}/g, nextPhase)
			.replace(/'█' \* chunk \+ '░' \* \(totalChunks - chunk\)/g, progressBar);
	}

	getInstructions(chunk: number, totalChunks: number): string {
		return this.instructions
			.replace(/\{chunk\}/g, String(chunk + 1))
			.replace(/\{totalChunks\}/g, String(totalChunks));
	}
}