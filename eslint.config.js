import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/*.d.ts'],
  },
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-console': ['error', { allow: ['error'] }],
    },
  },
  {
    // CLI, gateway startup, and scripts talk to humans via stdout by design.
    files: ['apps/cli/**', 'packages/gateway/src/start.ts', 'scripts/**'],
    rules: {
      'no-console': 'off',
    },
  }
);
