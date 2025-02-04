import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService, private jwtService: JwtService) {}

  async validateUser(username: string, password: string) {
    return await this.usersService.validateUser(username, password);
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.id, role: user.role };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    await this.usersService.updateRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken };
  }

  async refreshToken(oldRefreshToken: string) {
    try {
      const decoded = this.jwtService.verify(oldRefreshToken);
      const user = await this.usersService.findUser(decoded.username);

      if (!user || user.refreshToken !== oldRefreshToken) {
        throw new UnauthorizedException();
      }

      return this.login(user);
    } catch {
      throw new UnauthorizedException();
    }
  }
}
