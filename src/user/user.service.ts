import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  async getUsers() {
    const users= await this.prismaService.user.findMany({
      select : {
        id: true,
        firstname: true,
        email: true,
      }
    });
    return users;
  }

  async getUserById(userId: string) {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
      select : {
        id: true,
        firstname: true,
        email: true,
      }
    });
    return user;
  }
}
