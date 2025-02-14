import { Injectable } from '@nestjs/common';
import { AuthBody } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

export type UserPayload= {
    userId: string,
    email: string
}

export type RequestWithUser= {
    user: UserPayload
}

export type RegisterBody= {
    email: string,
    firstname: string
    password: string
}

@Injectable()
export class AuthService {
    constructor(
        private readonly prismaService: PrismaService,
        private jwtService: JwtService) { }

    async login(authBody: AuthBody) {
        const existingUser= await this.prismaService.user.findUnique({
            where: {
                email: authBody.email
            }
        });

        const hashPassword= await this.hashPassword(authBody.password);
        console.log('hashed password : ',hashPassword);
        
        if (!existingUser) {
            throw new Error("User not found");
        }

        const isPasswordValid = await this.isPasswordValid(authBody.password, existingUser.password);
        if (!isPasswordValid) {
            throw new Error("Invalid password");
        }

        const userPayload= {
            userId: existingUser.id,
            email: existingUser.email
        }

        return await this.authenticateUser(userPayload);
    }

    async register(registerBody: RegisterBody) {
        const { email, firstname, password }= registerBody;
        const existingUser= await this.prismaService.user.findUnique({
            where: {
                email: email
            }
        });

        if (existingUser) {
            throw new Error("User already existed!!!");
        }
        
        const hashedPassword= await this.hashPassword(password);

        const createdUser= await this.prismaService.user.create({
            data: {
                email: email,
                firstname: firstname,
                password: hashedPassword
            }
        });

        return await this.authenticateUser(
            {
                userId: createdUser.id,
                email: createdUser.email    
            }
        );
    }


    private async authenticateUser(userPayload: UserPayload) {
        const payload: UserPayload= userPayload;
        return {
            access_token: this.jwtService.sign(payload)
        }
    }

    private async hashPassword(password: string) {
        const hashedPassword = await bcrypt.hash(password, 10)
        return hashedPassword;
    }

    private async isPasswordValid(password: string, hashedPassword: string) {
        return await bcrypt.compare(password, hashedPassword);
    }
}
