import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { User } from './users.entity';

@Injectable()
export class UsersService {
  private users: User[] = [];

  async createUser(username: string, password: string, role: 'user' | 'admin' | 'moderator') {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser: User = { id: this.users.length + 1, username, password: hashedPassword, role };
    this.users.push(newUser);
    return newUser;
  }

  async findUser(username: string) {
    return this.users.find(user => user.username === username);
  }

  async validateUser(username: string, password: string) {
    const user = await this.findUser(username);
    if (user && await bcrypt.compare(password, user.password)) {
      return user;
    }
    return null;
  }

  async updateRefreshToken(id: number, refreshToken: string) {
    const user = this.users.find(user => user.id === id);
    if (user) {
      user.refreshToken = refreshToken;
    }
  }
}
