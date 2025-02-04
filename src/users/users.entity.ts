export class User {
    id: number;
    username: string;
    password: string;
    role: 'user' | 'admin' | 'moderator';
    refreshToken?: string;
  }
  