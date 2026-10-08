import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';

beforeEach(() => {
  localStorage.clear();
  // Every request must be mocked: tests cannot contact a real backend.
  vi.stubGlobal('fetch', vi.fn(() => {
    throw new Error('Unexpected fetch: configure a test response');
  }));
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  localStorage.clear();
});
