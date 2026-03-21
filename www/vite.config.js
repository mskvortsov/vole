import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { mockApiPlugin } from './mock.js';

export default defineConfig({
    plugins: [viteSingleFile(), mockApiPlugin()],
});
