import mongoose from "mongoose";


const MONGODB_URI = process.env.MONGODB_URI;

if(!MONGODB_URI){
    throw new Error("Please define MONGODB URI in .env.local");
}

type MongooseCache = {
    conn : typeof mongoose | null;
    promise : Promise<typeof mongoose> | null;
}

declare global {
    var mongooseCache: MongooseCache | undefined
};

const cached : MongooseCache = global.mongooseCache ?? {
    conn : null,
    promise : null
};

global.mongooseCache = cached;

export const connectToDatabase = async () => {

    if(cached.conn){
        return cached.conn;
    }

    if(!cached.promise){
        cached.promise = mongoose.connect(MONGODB_URI).then((instance) => instance);
    }

    try {

        cached.conn = await cached.promise;
        
    } catch (error) {
        cached.promise = null;
        throw error;
    }

    return cached.conn;
}