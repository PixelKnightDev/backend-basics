import mongoose, {Schema} from "mongoose";

const subscriptionSchema = new Schema({
    subscriber: {
        type: Schema.Types.ObjectId, // one who is subscribing
        ref: "Users"
    },
    channels: {
        type: Schema.Types.ObjectId, // to whom users are suscribing
        ref: "Users"
    }
},{ timestamps: true })



export const Subscription = mongoose.model("Subscription", subscriptionSchema)