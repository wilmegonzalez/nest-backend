import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginResponse } from './interfaces/login-response.interface';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ){}

  async create(createUserDto: CreateUserDto):Promise<User> {

    try {

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      await newUser.save();

      const {password:_, ...user } = newUser.toJSON()
      return user;
      
    } catch (err) {
      
       if(err.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exists!`);
      }
      throw new InternalServerErrorException('something terrible happened!')
     
      
    }

}

  async register(registerUserDto: RegisterUserDto):Promise<LoginResponse> {

    const user = await this.create(registerUserDto);


    return  {
      user: user,
      token: this.getJWT({id: user._id})

    }

  }

  async login( loginDto: LoginDto ){

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({email: email});

    if(!user){
      throw new UnauthorizedException('Not valid credentials - email');
    }
    
    if(!bcryptjs.compareSync(password, user.password)){
      
      throw new UnauthorizedException('Not valid credentials - password');
    }
    const { password:_, ...rest} = user.toJSON();

    return {
      user:rest,
      token:  this.getJWT({id: user.id})
     }

  }


  async findUserByID(id: string) {

    const user = await this.userModel.findById( id );
    const {password,...rest } = user.toJSON();
    return rest;
  }



  findAll():Promise<User[]> {
    return this.userModel.find()
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


  getJWT(payload: JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;

  }
}
