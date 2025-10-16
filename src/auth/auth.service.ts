import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as argon2 from 'argon2';

// We'll use database storage instead of in-memory blacklist

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private prisma: PrismaService,
    private jwtService: JwtService,
    @Inject('REFRESH_JWT_SERVICE') private refreshJwtService: JwtService,
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

  generateAccessToken(user: any): string {
    const payload = { 
      email: user.email, 
      sub: user.id, 
      name: user.name,
      type: 'access'
    };
    
    return this.jwtService.sign(payload);
  }

  generateRefreshToken(user: any): string {
    const payload = { 
      sub: user.id,
      type: 'refresh'
    };
    
    return this.refreshJwtService.sign(payload);
  }

  generateTokens(user: any) {
    return {
      access_token: this.generateAccessToken(user),
      refresh_token: this.generateRefreshToken(user),
    };
  }

  async login(user: any) {
    const tokens = this.generateTokens(user);
    
    // Hash and store the refresh token in database
    const hashedRefreshToken = await argon2.hash(tokens.refresh_token);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: hashedRefreshToken },
    });
    
    return {
      message: 'Login successful',
      ...tokens,
      expires_in: 900, // 15 minutes in seconds
      id: user.id,
      email: user.email,
    };
  }

  async refreshToken(refreshToken: string) {
    try {
      // Verify the refresh token using the refresh JWT service
      const payload = this.refreshJwtService.verify(refreshToken);

      // Check if it's actually a refresh token
      if (payload.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      // Get user from database
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });

      if (!user) {
        throw new Error('User not found');
      }

      // Check if the refresh token matches the stored hashed token
      if (!user.refreshToken || !await argon2.verify(user.refreshToken, refreshToken)) {
        throw new Error('Invalid refresh token');
      }

      // Generate new tokens
      const tokens = this.generateTokens(user);

      // Hash and store the new refresh token
      const hashedRefreshToken = await argon2.hash(tokens.refresh_token);
      await this.prisma.user.update({
        where: { id: user.id },
        data: { refreshToken: hashedRefreshToken },
      });

      return {
        message: 'Token refreshed successfully',
        ...tokens,
        expires_in: 900, // 15 minutes in seconds
        id: user.id,
        email: user.email,
      };
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  async logout(token: string) {
    try {
      // Verify the token to get user ID
      const payload = this.jwtService.verify(token);
      
      // Clear the refresh token from database
      await this.prisma.user.update({
        where: { id: payload.sub },
        data: { refreshToken: null },
      });
      
      return { message: 'Logged out successfully' };
    } catch (error) {
      // If token is invalid, still return success (user is effectively logged out)
      return { message: 'Logged out successfully' };
    }
  }
}
