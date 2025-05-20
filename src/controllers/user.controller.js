import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async(userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()


        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false }) // because when saving in mongoose, password validity kicks in from usermodel and we dont need it here 
             
        return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500, "something went wrong while generating access and refresh token")
    }
}

const registerUser = asyncHandler( async (req, res) => {
    // get user details from frontend
    // validation (all detail correct and not empty)
    // check if user already exists: both username and email
    // check for images, check for avatar
    // upload them to cloudinary
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return response


    const {fullName, email, username, password} = req.body
    //console.log("email:", password);
    //got all user data
    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }
    // you can check each by multiple if statements this code is more advanced
    // validation done
    const existingUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    //console.log(req.body);
    
    if(existingUser) {
        throw new ApiError(409, "user with email or username already exists")
    }

    //console.log(req.files);

    // checked if user exists or not
    const avatarLocalPath = req.files?.avatar[0]?.path; //multer ka feature hai
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.avatar[0].path
    }

    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }
    // more validation done (checked avatar) (also local path taken)


    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })
    // created user object and entered in db

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"  // weird syntax -something to remove that thing (everyting selected by default)
    )

    if(!createdUser) {
        throw new ApiError(500, "something went wrong while registering the user")
    }
    // checked for user creation

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )
    // returned response

})

const loginUser = asyncHandler(async (req, res) => {
    // req.body se data lelo
    // username or email kisi ek se login karwao
    // find the user
    // password check
    // access and refresh token
    // send cookies and successful response

    const {email, username, password} = req.body
    if (!username && !email) {
        throw new ApiError(400, "username and email are required")
    }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })
    if(!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    // here we use user.isPasswordCorrect lowercase user not User because the method was created by us if mongoose method like findone then User but for our method use your variable
    if(!isPasswordValid) {
        throw new ApiError(401, "password incorrect")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)
    
    const loggedInUser = await User.findById(user._id).
    select("-password -refreshToken")

    const options = {
        httplOnly: true,
        secure: true
    }
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser,
                accessToken,
                refreshToken
            },
            "User logged in Successfully"
        )
    )
})

const logoutUser = asyncHandler(async(req,res) => {
    await User.findByIdAndUpdate(
        req.user._id,  // we got this because of the auth middleware, in login we take from the user by req.body but here we cant so we take from cookie using cookie parser in middleware and add it to req before reaching here.(big brain)
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }
    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
})

const refreshAccessToken = asyncHandler(async(req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }
    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
        const user = await User.findById(decodedToken?._id)
        if(!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "refresh token is expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }


})

const changeCurrentPassword = asyncHandler(async(req,res) => {
    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect) {
        throw new ApiError(400, "incorrect old password")
    }
    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "password changed successfully"))
})

const getCurrentUser = asyncHandler(async(req, res) => {
    //const user = await User.findById(req.user?.id)
    // already have req.user from middleware so no need to find by id
    return res
    .status(200)
    .json(new ApiResponse(200, req.user, "current user fetched successfully"))
})

const updateAccountDetails = asyncHandler(async(req, res) => {
    const {fullName, email} = req.body

    if(!(fullName && email)) {
        throw new ApiError(400, "All fields are required")
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName: fullName,
                email: email
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"))
})

const updateUserAvatar = asyncHandler(async(req, res) => {
   const avatarLocalPath = req.file?.path 

   if (!avatarLocalPath) {
        throw new ApiError(400, "avatar file is missing")
   }
   const avatar = await uploadOnCloudinary(avatarLocalPath)
   if(!avatar.url) {
        throw new ApiError(400, "error while uploading on avatar")
   }
   const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
        $set: {
            avatar: avatar.url
        }
    },
    {new: true}
    ).select("-password")
    return res
    .status(200)
    .json(new ApiResponse(200, user, "Avatar image updated"))
})
// create a utility to delete the old cloudinary upload
const updateUserCoverImage = asyncHandler(async(req, res) => {
   const coverImageLocalPath = req.file?.path 

   if (!coverImageLocalPath) {
        throw new ApiError(400, "coverImage file is missing")
   }
   const coverImage = await uploadOnCloudinary(coverImageLocalPath)
   if(!coverImage.url) {
        throw new ApiError(400, "error while uploading on coverImage")
   }
   const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
        $set: {
            coverImage: coverImage.url
        }
    },
    {new: true}
    ).select("-password")
    return res
    .status(200)
    .json(new ApiResponse(200, user, "cover image updated"))
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
}