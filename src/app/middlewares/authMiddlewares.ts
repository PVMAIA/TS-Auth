import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface TokenPayLoadProps {
   id: string;
   iat: number;
   exp: number;
}

export default function authMiddleware(req:Request, res: Response, next: NextFunction) {
   const { authorization } = req.headers;

   if(!authorization) {
      res.sendStatus(401);
   }

   const token = authorization?.replace('Bearer', '').trim();

   try {
      const data = jwt.verify(token ?? 'default-token', 'secret');
      
      const { id } = data as TokenPayLoadProps;

      req.userId = id;
      
      return next();
   } catch {
      res.sendStatus(401);
   }
}