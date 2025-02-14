import { Controller, Get, Param } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('api/users')
export class UserController {
    constructor (private userService: UserService) {}

    @Get('getAll')
    getUsers() {
        return this.userService.getUsers();
    }

    @Get('getById/:userId')
    getUserById(@Param('userId') userId: string) {
        return this.userService.getUserById(userId);
    }
}
