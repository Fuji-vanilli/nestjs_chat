import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from 'src/prisma.service';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: jwtConstants.JWT_SECRET,
      signOptions: { expiresIn: '3600s' },
    })
  ],
  controllers: [AuthController],
  providers: [
    AuthService, 
    PrismaService,
    JwtStrategy
  ]
})
export class AuthModule {}
