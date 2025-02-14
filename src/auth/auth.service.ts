import { Injectable } from '@nestjs/common';
import { AuthBody } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(private readonly prismaService: PrismaService) { }

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

        return existingUser;
    }

    private async hashPassword(password: string) {
        const hashedPassword = await bcrypt.hash(password, 10)
        return hashedPassword;
    }

    private async isPasswordValid(password: string, hashedPassword: string) {
        return await bcrypt.compare(password, hashedPassword);
    }
}
