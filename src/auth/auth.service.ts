import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterDto } from './dto';
import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

import * as bcryptjs from 'bcryptjs';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name )
    private userModel: Model<User>,
    private jwtService: JwtService

  ) {}
  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try{
      const { password, ...userData} = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });

      //1. Encriptar la contraseña
      //2. Guardar el usuario
      //3. Generar JWT
      //4. Manejo de erorres
      
      await newUser.save();
      const {password:_, ...user} = newUser.toJSON();

      //Es para que no mostremos el hash tras la peticion, queda raro
      return user;

    } catch(err) {
      if(err.code == 11000) {
        throw new BadRequestException(`${ createUserDto.email } already exists!`);
      }
      throw new InternalServerErrorException('Something terrible happened!!');
    }

  }

  async register( registerDto: RegisterDto ): Promise<LoginResponse> {
    const { email, name, password, ..._ } = registerDto;
    const user = await this.create({name, email, password});
    return {
      user,
      token: this.getJWT({id: user._id })
    }
  }

  /**
   * User ->  {_id, name, email, roles}\
   * Token -> JWT
  */
  async login( loginDto: LoginDto ): Promise<LoginResponse> {
    
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if(!user) {
      throw new UnauthorizedException('Not valid credentials - email');
    }

    if(!bcryptjs.compareSync( password, user.password )) {
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const {password:_, ...rest} = user.toJSON();

    return {
      user: rest,
      token: this.getJWT({id: user.id })
    };

  }

  findAll(): Promise<User[]>{
    return this.userModel.find();
  }

  async findUserById( id: string ) {
    const user = await this.userModel.findById( id );
    const { password, ...rest} = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWT(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
