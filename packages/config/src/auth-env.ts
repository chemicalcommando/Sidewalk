import { z } from 'zod';

export const authEnvSchema = z
  .object({
    JWT_SECRET: z.string().trim().min(1).optional(),
    JWT_PRIVATE_KEY: z.string().trim().min(1).optional(),
    JWT_PUBLIC_KEY: z.string().trim().min(1).optional(),
    ACCESS_TOKEN_EXPIRES_IN: z.string().trim().min(1).default('15m'),
    REFRESH_TOKEN_EXPIRES_IN: z.string().trim().min(1).default('30d'),
  })
  .refine((v) => v.JWT_SECRET || (v.JWT_PRIVATE_KEY && v.JWT_PUBLIC_KEY), {
    message:
      'JWT configuration missing. Set JWT_SECRET or both JWT_PRIVATE_KEY and JWT_PUBLIC_KEY.',
    path: ['JWT_SECRET'],
  });

export type AuthEnv = z.infer<typeof authEnvSchema>;

/**
 * Validates auth-critical environment variables and throws with actionable
 * variable names on failure. Call once at startup before any auth flows run.
 */
export function validateAuthEnv(env: NodeJS.ProcessEnv = process.env): AuthEnv {
  const result = authEnvSchema.safeParse(env);
  if (!result.success) {
    const details = result.error.issues
      .map((i) => `${i.path.join('.') || 'env'}: ${i.message}`)
      .join('; ');
    throw new Error(`Auth environment invalid — ${details}`);
  }
  return result.data;
}
