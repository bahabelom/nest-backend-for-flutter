import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DatabaseService } from './database/database.service';
import { UsersService } from './users/users.service';
import { UsersController } from './users/users.controller';
import { User } from './entities/user.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        return {
          type: 'postgres',
          host: configService.get('DB_HOST', 'localhost'),
          port: configService.get('DB_PORT', 5432),
          username: configService.get('DB_USER', 'postgres'),
          password: configService.get('DB_PASSWORD', 'password'),
          database: configService.get('DB_NAME', 'norem'),
          entities: [User],
          synchronize: configService.get('DB_SYNCHRONIZE_ENTITIES') === 'true' || configService.get('NODE_ENV') === 'development',
          logging: false,
        };
      },
      inject: [ConfigService],
    }),
    TypeOrmModule.forFeature([User]),
  ],
  controllers: [AppController, UsersController],
  providers: [AppService, DatabaseService, UsersService],
})
export class AppModule {}
