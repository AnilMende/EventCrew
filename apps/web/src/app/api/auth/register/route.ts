import { connectToDatabase } from "@/lib/db/mongodb";
import { registerSchema } from "@/lib/validations/auth";
import { UserModel } from "@/models/User";
import bcrypt from "bcryptjs";
import { NextRequest } from "next/server";


export const POST = async (request: NextRequest) => {

    try {

        // parse the incoming data
        let body : unknown;

        try {
            body = await request.json();
            
        } catch {
            return Response.json(
                { success : false, message : "Invalid JSON request body"},
                { status : 400 }
            );
        }

        // validate the request with the zod
        const result = registerSchema.safeParse(body);

        if(!result.success){
            return Response.json(
                {
                    success : false,
                    message : "validation failed",
                    errors : result.error.flatten().fieldErrors,
                },
                { status : 400 }
            );
        }

        const { name, email, password } = result.data;

        // bcrypt processes a maximum of 72 password bytes
        if(Buffer.byteLength(password, "utf8") > 72){
            return Response.json(
                {
                    success : false,
                    message : "Password must not exceed 72 bytes"
                },
                { status : 400 }
            );
        }

        // connect to Database
        await connectToDatabase();

        // check whether the email is already registered
        const existingUser = await UserModel.findOne({ email });

        if(existingUser){
            return Response.json(
                { success : false, message : "Email is already registered"},
                { status : 409 }
            );
        }

        // hash the password before saving
        const passwordHash = await bcrypt.hash(password, 12);

        // create the user
        const user = await UserModel.create({
            name,
            email,
            passwordHash,
            role : "customer"
        });

        // return only safe user fields
        return Response.json(
            {
                success : true,
                message : "Account created successfully",
                user : {
                    id : user._id.toString(),
                    name : user.name,
                    email : user.email,
                    role : user.role,
                    isEmailVerified : user.isEmailVerified,
                    createdAt : user.createdAt
                },
            },
            { status : 201 }
        );

        
    } catch (error: unknown) {
        
        if(
            typeof error === "object" &&
            error !== null &&
            "code" in error &&
            error.code === 11000
        ){
            return Response.json(
                { success: false, message : "Email is already registered"},
                { status : 409}
            );
        }

        console.error("Registration failed:", error);

        return Response.json(
            { success : false, message : "Unable to create account"},
            { status : 500 }
        );
    }
};