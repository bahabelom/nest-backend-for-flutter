import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (user && await bcrypt.compare(password, user.password)) {
      const { password: _, ...result } = user;
      return result;
    }
    return null;
  }

  generateJwtToken(user: any): string {
    const payload = { 
      email: user.email, 
      sub: user.id, 
      name: user.name 
    };
    
    return this.jwtService.sign(payload);
  }

  async login(user: any) {
    return {
      message: 'Login successful',
      access_token: this.generateJwtToken(user),
      id: user.id,
      email: user.email,
    };
  }
}
