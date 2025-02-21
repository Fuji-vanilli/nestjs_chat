import { Body, Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { AuthService, RegisterBody, RequestWithUser } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { UserService } from 'src/user/user.service';

export type AuthBody= {
    email: string, 
    password: string
}


@Controller('api/auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private userService: UserService
    ) { }

    @Post('login')
    async login(@Body() authBody: AuthBody) {
        return await this.authService.login(authBody);
    }

    @Post('register')
    async register(@Body() registerBody: RegisterBody) {
        return await this.authService.register(registerBody);
    }

    @UseGuards(JwtAuthGuard)
    @Get()
    async authenticate(@Request() req) {
        return await this.userService.getUserById(req.user.payload.userId);
    }
}
