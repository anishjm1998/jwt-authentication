import { Controller, Post, Body, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService, private usersService: UsersService) {}

  @Post('register')
  async register(@Body() body) {
    return this.usersService.createUser(body.username, body.password, body.role);
  }

  @Post('login')
  async login(@Body() body) {
    const user = await this.authService.validateUser(body.username, body.password);
    if (!user) throw new Error('Invalid credentials');
    return this.authService.login(user);
  }

  @Post('refresh')
  async refresh(@Body() body) {
    return this.authService.refreshToken(body.refreshToken);
  }
}
