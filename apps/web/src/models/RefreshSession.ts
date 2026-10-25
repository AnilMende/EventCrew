import { Types, Schema, models, model, type Model } from "mongoose";

export interface IRefreshSession {
    userId: Types.ObjectId;
    sessionId: string;
    tokenHash: string;
    expiresAt: Date;
    revokedAt: Date | null;
    createdAt?: Date;
    updatedAt?: Date;
}

const refreshSessionSchema = new Schema<IRefreshSession>(
    {
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },
        sessionId: {
            type: String,
            required: true,
            unique: true
        },
        tokenHash: {
            type: String,
            required: true
        },
        expiresAt: {
            type: Date,
            required: true,
            index: true
        },
        revokedAt: {
            type: Date,
            default: null
        }
    },
    { timestamps: true }
);

export const RefreshSessionModel = (models.RefreshSession as Model<IRefreshSession>) ||
    model<IRefreshSession>("RefreshSession", refreshSessionSchema)