import { Module, OnModuleInit } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    MongooseModule.forRoot('mongodb://127.0.0.1:27017/jwt-auth'),
    AuthModule,
    UsersModule,
  ],
})
export class AppModule implements OnModuleInit {
  onModuleInit() {
    console.log('✅ Connected to MongoDB successfully!');
  }
}
