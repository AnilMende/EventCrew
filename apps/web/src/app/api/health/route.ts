import { connectToDatabase } from "@/lib/db/mongodb"

export const GET = async () => {


    try {

        await connectToDatabase();

        return Response.json({
            success : true,
            message : "EventCrew API is running",
            database : "connected"
        });
        
    } catch (error) {
        console.error("Database connection failed: ", error);

        return Response.json(
            {
            success : false,
            message : "Database connection failed"
        },
        { status : 500 }
    );

    }
}