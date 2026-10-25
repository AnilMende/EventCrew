import { model, Model, models, Schema } from "mongoose";


export type UserRole = "customer" | "professional" | "admin";

export interface IUser {

    name : string;
    email : string;
    passwordHash : string;
    role : UserRole;
    isEmailVerified : boolean;
    isActive : boolean;
    createdAt?: Date;
    updatedAt?: Date;

}

const userSchema = new Schema<IUser>(
    {
        name : {
            type : String,
            required : [true, "Name is required"],
            trim : true,
            minlength : [2, "Name must be atleast 2 characters"],
            maxlength : [20, "Name can not exceed 20 characters"]
        },

        email : {
            type : String,
            required : [true, "Email is required"],
            unique : true,
            lowercase : true,
            trim : true
        },

        passwordHash : {
            type : String,
            required : [true, "Password Hash is required"],
            select : false
        },

        role : {
            type : String,
            enum : ["customer", "professional", "admin"],
            default : "customer",
            required : true
        },

        isEmailVerified : {
            type : Boolean,
            default : false
        },

        isActive : {
            type : Boolean,
            default : true
        }
    },
    { timestamps : true }
);
// Look into the global registry to see if the 'User' model already exists.
// If it does, reuse it and type it properly.
// If it doesn't exist yet, create a brand new one using our schema definition.
export const UserModel = (models.User as Model<IUser>) || model<IUser>("User", userSchema);