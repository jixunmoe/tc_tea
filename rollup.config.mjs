import { defineConfig } from 'rollup';
import typescript from '@rollup/plugin-typescript';
import { dts } from 'rollup-plugin-dts';

export default defineConfig([
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/tc_tea.cjs',
      format: 'cjs',
    },
    plugins: [typescript()],
  },
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/tc_tea.mjs',
      format: 'es',
    },
    plugins: [typescript()],
  },
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/tc_tea.d.ts',
      format: 'es',
    },
    plugins: [dts()],
  },
]);
