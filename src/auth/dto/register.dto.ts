import { IsEmail, IsString, MinLength } from "class-validator";

export class RegisterDto {

    @IsEmail()
    email: string;

    @IsString()
    name: string;

    @MinLength(6)
    password: string;

    @MinLength(6)
    password2: string;
}