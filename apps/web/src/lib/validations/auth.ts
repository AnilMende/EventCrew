import {z} from "zod";

export const registerSchema = z.object({

    name : z
    .string()
    .trim()
    .min(2, "Name must be atleast 2 characters")
    .max(20, "Name can not exceed 20 characters"),

    email : z
    .string()
    .trim()
    .email("Please provide an valid email addess")
    .transform(email => email.toLowerCase()),

    password : z
    .string()
    .min(8, "Password must be atleast 8 characters")
    .max(16, "Password can not exceed 16 characters")
})

export const loginSchema = z.object({

    email : z
    .string()
    .trim()
    .email("Please provide a valid email address")
    .transform((email) => email.toLowerCase()),

    password : z
    .string()
    .min(1, "Password is required")
    .max(16, "Password can not exceed 16 characters")
});

export type LoginInput = z.infer<typeof loginSchema>;

export type RegisterInput = z.infer<typeof registerSchema>;