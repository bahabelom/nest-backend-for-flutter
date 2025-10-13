import { ConfigService } from '@nestjs/config';
import { JwtModuleOptions } from '@nestjs/jwt';

export default {
  asProvider() {
    return {
      imports: [],
      useFactory: async (configService: ConfigService): Promise<JwtModuleOptions> => {
        return {
          secret: configService.get<string>('JWT_SECRET'),
          signOptions: {
            expiresIn: (configService.get<string>('JWT_EXPIRES_IN') || '24h') as any,
          },
        };
      },
      inject: [ConfigService],
    };
  },
};
