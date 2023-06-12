/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import config from 'config'
import crypto from 'crypto'
import {
  InferAttributes,
  InferCreationAttributes,
  Model,
  DataTypes,
  CreationOptional,
  Sequelize
} from 'sequelize'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const challenges = require('../data/datacache').challenges

class User extends Model<
InferAttributes<User>,
InferCreationAttributes<User>
> {
  declare id: CreationOptional<number>
  declare username: string | undefined
  declare email: CreationOptional<string>
  declare password: CreationOptional<string>
  declare role: CreationOptional<string>
  declare deluxeToken: CreationOptional<string>
  declare lastLoginIp: CreationOptional<string>
  declare profileImage: CreationOptional<string>
  declare totpSecret: CreationOptional<string>
  declare isActive: CreationOptional<boolean>
}

const UserModelInit = (sequelize: Sequelize) => { 
  User.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      username: {
        type: DataTypes.STRING,
        defaultValue: '',
        set (username: string) {
          this.setDataValue('username', security.sanitizeSecure(username))
        }
      },
      email: {
        type: DataTypes.STRING,
        unique: true,
        set (email: string) {
          if (!utils.disableOnContainerEnv()) {
            challengeUtils.solveIf(challenges.persistedXssUserChallenge, () => {
              return utils.contains(
                email,
                '<iframe src="javascript:alert(`xss`)">'
              )
            })
          } else {
            email = security.sanitizeSecure(email)
          }
          this.setDataValue('email', email)
        }
      },
      password: {
        type: DataTypes.STRING,
        set (clearTextPassword: any) {
          this.setDataValue('password', crypto.createHash('md5').update(clearTextPassword).digest('hex'))
        }
      },
      role: {
        type: DataTypes.STRING,
        defaultValue: 'customer',
        validate: {
          isIn: [['customer', 'deluxe', 'accounting', 'admin']]
        },
        set (role: string) {
          const profileImage = this.getDataValue('profileImage')
          if (
            role === security.roles.admin &&
          (!profileImage ||
            profileImage === '/assets/public/images/uploads/default.svg')
          ) {
            this.setDataValue(
              'profileImage',
              '/assets/public/images/uploads/defaultAdmin.png'
            )
          }
          this.setDataValue('role', role)
        }
      },
      deluxeToken: {
        type: DataTypes.STRING,
        defaultValue: ''
      },
      lastLoginIp: {
        type: DataTypes.STRING,
        defaultValue: '0.0.0.0'
      },
      profileImage: {
        type: DataTypes.STRING,
        defaultValue: '/assets/public/images/uploads/default.svg'
      },
      totpSecret: {
        type: DataTypes.STRING,
        defaultValue: ''
      },
      isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      }
    },
    {
      tableName: 'Users',
      paranoid: true,
      sequelize
    }
  )

}

export { User as UserModel, UserModelInit }
